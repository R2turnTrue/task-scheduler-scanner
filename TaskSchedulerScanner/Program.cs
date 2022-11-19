using System;
using System.Transactions;
using Microsoft.Win32.TaskScheduler;

namespace TaskSchedulerScanner // Note: actual namespace depends on the project name.
{
    internal class Program
    {
        private static List<ActionCollection> susActions = new List<ActionCollection>();

        static void Main(string[] args)
        {
            var instance = new Program();
            Console.WriteLine("Querying suspicious tasks");
            instance.EnumAllTasks();
            Console.Write("Do you want to see suspicious exec actions of the suspicious tasks? (Y/N): ");
            var t = Console.ReadLine();
            if (t.ToUpper() == "Y")
            {
                instance.EnumAllActions();
            }

            Console.WriteLine("----- Press any key to exit!");
            Console.ReadKey();
        }
        
        public void EnumAllTasks()
        {
            EnumFolderTasks(TaskService.Instance.RootFolder);
        }

        void EnumFolderTasks(TaskFolder fld)
        {
            foreach (Microsoft.Win32.TaskScheduler.Task task in fld.Tasks)
                ActOnTask(task);
            foreach (TaskFolder sfld in fld.SubFolders)
                EnumFolderTasks(sfld);
        }

        void ActOnTask(Microsoft.Win32.TaskScheduler.Task t)
        {
            var suspiciousTriggers = t.Definition.Triggers.Where((trigger) =>
            {
                return trigger.TriggerType == TaskTriggerType.Boot || trigger.TriggerType == TaskTriggerType.Idle || trigger.TriggerType == TaskTriggerType.Logon;
            });

            if (suspiciousTriggers.Any())
            {
                Console.WriteLine("Suspicious Task: " + t.Path);
                susActions.Add(t.Definition.Actions);
            }
        }

        public void EnumAllActions()
        {
            foreach (var actions in susActions)
            {
                foreach (var action in actions)
                {
                    if (action.ActionType == TaskActionType.Execute)
                    {
                        var execAction = (ExecAction) action;
                        Console.WriteLine(execAction.Path + " " + execAction.Arguments + (execAction.WorkingDirectory != "" + "(It works at " + execAction.WorkingDirectory + ")"));
                    }
                }
            }
        }
    }
}